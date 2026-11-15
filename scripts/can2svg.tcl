#  can2svg.tcl ---
#  
#      This file provides translation from canvas commands to XML/SVG format.
#      
#  Copyright (c) 2002-2007  Mats Bengtsson
#  
#  This file is distributed under BSD style license.
#
# $Id: can2svg.tcl,v 1.26 2008-01-27 08:19:36 matben Exp $
# 
# ########################### USAGE ############################################
#
#   NAME
#      can2svg - translate canvas command to SVG.
#      
#   SYNOPSIS
#      can2svg canvasCmd ?options?
#           canvasCmd is everything except the widget path name.
#           
#      can2svg::canvas2file widgetPath fileName ?options?
#           options:   -height
#                      -width
#      
#      can2svg::can2svg canvasCmd ?options?
#           options:    -httpbasedir        path
#                       -imagehandler       tclProc
#                       -ovalasellipse      0|1
#                       -reusedefs          0|1
#                       -uritype            file|http
#                       -usestyleattribute  0|1
#                       -usetags            0|all|first|last
#                       -windowitemhandler  tclProc
#                       
#      can2svg::config ?options?
#           options:        -allownewlines      0
#                        -filtertags         ""
#                        -httpaddr           localhost
#                        -ovalasellipse      0
#                        -reusedefs          1
#                        -uritype            file
#                        -usetags            all
#                        -usestyleattribute  1
#                       -windowitemhandler  tclProc
#
# ########################### CHANGES ##########################################
#
#   0.1      first release
#   0.2      URI encoded image file path
#   0.3      uses xmllists more, added svgasxmllist
#
# ########################### TODO #############################################
# 
#   handle units (m->mm etc.) 
#   better support for stipple patterns
#   how to handle tk editing? DOM?
#   
#   ...

# We need URN encoding for the file path in images. From my whiteboard code.

#package require uriencode
#package require tinyfileutils

package provide can2svg 0.3


namespace eval can2svg {

    namespace export can2svg canvas2file
    
    variable confopts
    array set confopts {
        -allownewlines        0
        -filtertags           ""
        -httpaddr             localhost
        -ovalasellipse        0
        -reusedefs            1
        -uritype              file
        -usetags              all
        -usestyleattribute    1
        -windowitemhandler    ""
    }
    set confopts(-httpbasedir) [info script]
    
    variable formatArrowMarker
    variable formatArrowMarkerLast
    
    # The key into this array is 'arrowMarkerDef_$col_$a_$b_$c', where
    # col is color, and a, b, c are the arrow's shape.
    variable defsArrowMarkerArr

    # Similarly for stipple patterns.
    variable defsStipplePatternArr

    # This shouldn't be hardcoded!
    variable defaultFont {Helvetica 12}

    variable pi 3.14159265359
    variable anglesToRadians [expr $pi/180.0]
    variable grayStipples {gray75 gray50 gray25 gray12}
        
    # Make 4x4 squares. Perhaps could be improved.
    variable stippleDataArr
    
    set stippleDataArr(gray75)  \
      {M 0 0 h3  M 0 1 h1 M 2 1 h2
       M 0 2 h3  M 0 3 h1 M 2 3 h1}
    set stippleDataArr(gray50)  \
      {M 0 0 h1 M 2 0 h1  M 1 1 h1 M 3 1 h1
       M 0 2 h1 M 2 2 h1  M 1 3 h1 M 3 3 h1}
    set stippleDataArr(gray25)  \
      {M 3 0 h1 M 1 1 h1 M 3 2 h1 M 1 3 h1}
    set stippleDataArr(gray12)  \
      {M 1 1 h1 M 3 3 h1}
    
}

proc can2svg::config {args} {
    variable confopts
    
    set options [lsort [array names confopts -*]]
    set usage [join $options ", "]
    if {[llength $args] == 0} {
        set result {}
        foreach name $options {
            lappend result $name $confopts($name)
        }
        return $result
    }
    regsub -all -- - $options {} options
    set pat ^-([join $options |])$
    if {[llength $args] == 1} {
        set flag [lindex $args 0]
        if {[regexp -- $pat $flag]} {
            return $confopts($flag)
        } else {
            return -code error "Unknown option $flag, must be: $usage"
        }
    } else {
        foreach {flag value} $args {
            if {[regexp -- $pat $flag]} {
                set confopts($flag) $value
            } else {
                return -code error "Unknown option $flag, must be: $usage"
            }
        }
    }
}

# can2svg::can2svg --
#
#       Make xml out of a canvas command, widgetPath removed.
#       
# Arguments:
#       cmd         canvas create commands without prepending widget path.
#       args    -httpbasedir        path
#               -imagehandler       tclProc
#               -ovalasellipse      0|1
#               -reusedefs          0|1
#               -uritype            file|http
#               -usestyleattribute  0|1
#               -usetags            0|all|first|last
#       
# Results:
#   xml data

proc can2svg::can2svg {cmd args} {

    set xml ""
    foreach xmllist [eval {svgasxmllist $cmd} $args] {
        append xml [MakeXML $xmllist]
    }
    return $xml
}

# can2svg::svgasxmllist --
#
#       Make a list of xmllists out of a canvas command, widgetPath removed.
#       
# Arguments:
#       cmd         canvas create command without prepending widget path.
#       args    -httpbasedir        path
#               -imagehandler       tclProc
#               -ovalasellipse      0|1
#               -reusedefs          0|1
#               -uritype            file|http
#               -usestyleattribute  0|1
#               -usetags            0|all|first|last
#       
# Results:
#       a list of xmllist = {tag attrlist isempty cdata {child1 child2 ...}}

proc can2svg::svgasxmllist {cmd args} {
    
    variable confopts
    variable defsArrowMarkerArr
    variable defsStipplePatternArr
    variable defaultFont
    variable grayStipples
        
    set nonum_ {[^0-9]}
    set wsp_ {[ ]+}
    set xmlLL [list]
    
    array set argsA [array get confopts]
    array set argsA $args
    set args [array get argsA]
    
    if {![string equal [lindex $cmd 0] "create"]} {
        return
    }
    
    set type [lindex $cmd 1]
    set rest [lrange $cmd 2 end]
    
    # Separate coords from options.
    set indopt [lsearch -regexp $rest "-${nonum_}"]
    if {$indopt < 0} {
        set ind end
        set opts [list]
    } else {
        set ind [expr $indopt - 1]
        set opts [lrange $rest $indopt end]
    }
    
    # Flatten coordinate list!
    set coo [lrange $rest 0 $ind]
    if {[llength $coo] == 1} {
        set coo [lindex $coo 0]
    }
    array set optA $opts
    
    # Is the item in normal state? If not, return.
    if {[info exists optA(-state)] && $optA(-state) != "normal"} {
        return
    }
    
    # Figure out if we've got a spline.
    set haveSpline 0
    if {[info exists optA(-smooth)] && ($optA(-smooth) != "0") &&  \
      [info exists optA(-splinesteps)] && ($optA(-splinesteps) > 2)} {
        set haveSpline 1
    }
    if {[info exists optA(-fill)]} {
        set fillValue $optA(-fill)
        if {![regexp {#[0-9]+} $fillValue]} {
            set fillValue [FormatColorName $fillValue]
        }
    } else {
        set fillValue black
    }
    if {[string length $argsA(-filtertags)] && [info exists optA(-tags)]} {
        set tag [uplevel #0 $argsA(-filtertags) [list $optA(-tags)]]
        set idAttr [list id $tag]
    } elseif {($argsA(-usetags) != "0") && [info exists optA(-tags)]} {
        
        # Remove any 'current' tag.
        set optA(-tags) \
          [lsearch -all -not -inline $optA(-tags) current]
        
        switch -- $argsA(-usetags) {
            all {                        
                set idAttr [list id $optA(-tags)]
            }
            first {
                set idAttr [list id [lindex $optA(-tags) 0]]
            }
            last {
                set idAttr [list id [lindex $optA(-tags) end]]
            }
        }
    } else {
        set idAttr ""
    }
    
    # If we need a marker (arrow head) need to make that first.
    if {[info exists optA(-arrow)] && ![string equal $optA(-arrow) "none"]} {
        if {[info exists optA(-arrowshape)]} {
            
            # Make a key of the arrowshape list into the array.
            regsub -all -- $wsp_ $optA(-arrowshape) _ shapeKey
            set arrowKey ${fillValue}_${shapeKey}
            set arrowShape $optA(-arrowshape)
        } else {
            set arrowKey ${fillValue}
            set arrowShape {8 10 3}
        }
        if {!$argsA(-reusedefs) || \
          ![info exists defsArrowMarkerArr($arrowKey)]} {
            set defsArrowMarkerArr($arrowKey)  \
              [eval {MakeArrowMarker} $arrowShape {$fillValue}]
            set xmlLL \
              [concat $xmlLL $defsArrowMarkerArr($arrowKey)]
        }
    }
    
    # If we need a stipple bitmap, need to make that first. Limited!!!
    # Only: gray12, gray25, gray50, gray75
    foreach key {-stipple -outlinestipple} {
        if {[info exists optA($key)] &&  \
          ([lsearch $grayStipples $optA($key)] >= 0)} {
            set stipple $optA($key)
            if {![info exists defsStipplePatternArr($stipple)]} {
                set defsStipplePatternArr($stipple)  \
                  [MakeGrayStippleDef $stipple]
            }
            lappend xmlLL $defsStipplePatternArr($stipple)
        }
    }
    ### puts "can2svg::svgasxmllist cmd=$cmd, args=$args"
    
    switch -- $type {
        
        arc {
            
            # Had to do it the hard way! (?)
            # "Wrong" coordinate system :-(
            set attr [CoordsToAttr $type $coo $opts elem]            
            if {[string length $idAttr] > 0} {
                set attr [concat $attr $idAttr]
            }
            set attr [concat $attr [MakeAttrList \
              $type $opts $argsA(-usestyleattribute)]]
            lappend xmlLL [MakeXMLList $elem -attrlist $attr]
        }
        bitmap - image {
            if {[info exists optA(-image)]} {
                set elem "image"
                set attr [eval {MakeImageAttr $coo $opts} $args]
                if {[string length $idAttr] > 0} {
                    set attr [concat $attr $idAttr]
                }
                set subEs [list]
                if {[info exists argsA(-imagehandler)]} {
                    set subE [uplevel #0 $argsA(-imagehandler) [list $cmd] $args]
                    if {[llength $subE]} {
                        set subEs [list $subE]
                    }
                }
                lappend xmlLL [MakeXMLList $elem -attrlist $attr -subtags $subEs]
            }
        }
        line {
            set attr [CoordsToAttr $type $coo $opts elem]            
            if {[string length $idAttr] > 0} {
                set attr [concat $attr $idAttr]
            }                    
            set attr [concat $attr [MakeAttrList \
              $type $opts $argsA(-usestyleattribute)]]
            lappend xmlLL [MakeXMLList $elem -attrlist $attr]
        }
        oval {
            set attr [CoordsToAttr $type $coo $opts elem]            
            foreach {x y w h} [NormalizeRectCoords $coo] break
            if {[expr $w == $h] && !$argsA(-ovalasellipse)} {
                # set elem "circle";# circle needs an r: not an rx & ry
                set elem "ellipse"
            } else {
                set elem "ellipse"
            }
            if {[string length $idAttr] > 0} {
                set attr [concat $attr $idAttr]
            }
            set attr [concat $attr [MakeAttrList \
              $type $opts $argsA(-usestyleattribute)]]
            lappend xmlLL [MakeXMLList $elem -attrlist $attr]
        }
        polygon {
            set attr [CoordsToAttr $type $coo $opts elem]            
            if {[string length $idAttr] > 0} {
                set attr [concat $attr $idAttr]
            }
            set attr [concat $attr [MakeAttrList \
              $type $opts $argsA(-usestyleattribute)]]
            lappend xmlLL [MakeXMLList $elem -attrlist $attr]
        }
        rectangle {
            set attr [CoordsToAttr $type $coo $opts elem]            
            if {[string length $idAttr] > 0} {
                set attr [concat $attr $idAttr]
            }
            set attr [concat $attr [MakeAttrList \
              $type $opts $argsA(-usestyleattribute)]]
            lappend xmlLL [MakeXMLList $elem -attrlist $attr]
        }
        text {
            set elem "text"
            set chdata ""
            set nlines 1
            if {[info exists optA(-font)]} {
                set theFont $optA(-font)
            } else {
                set theFont $defaultFont
            }
            set ascent [font metrics $theFont -ascent]
            set lineSpace [font metrics $theFont -linespace]
            if {[info exists optA(-text)]} {
                set chdata $optA(-text)
                
                if {[info exists optA(-width)]} {
                    
                    # MICK O'DONNELL: if the text is wrapped in the wgt, we need
                    # to simulate linebreaks
                    # 
                    # If the item has got -width != 0 then we must wrap it ourselves
                    # using newlines since the -text does not have extra newlines
                    # at these linebreaks.
                    set lines [split $chdata \n]
                    set newlines {}
                    foreach line $lines {
                        set lines2 [SplitWrappedLines $line $theFont $optA(-width)]
                        set newlines [concat $newlines $lines2]
                    }
                    set chdata [join $newlines \n]
                    if {!$argsA(-allownewlines) || \
                      ([llength $newlines] > [llength $lines])} {
                        set nlines [expr [regexp -all "\n" $chdata] + 1]
                    }
                } else {
                    if {!$argsA(-allownewlines)} {
                        set nlines [expr [regexp -all "\n" $chdata] + 1]
                    }
                }
            }
            
            # Figure out the coords of the first baseline.
            set anchor center
            if {[info exists optA(-anchor)]} {
                set anchor $optA(-anchor)
            }                                        
            
            foreach {xbase ybase}  \
              [GetTextSVGCoords $coo $anchor $chdata $theFont $nlines] {}
            
            set attr [list "x" $xbase "y" $ybase]
            # angle is negated in order to fit 
            # canvas coordinate system
            if {[info exists optA(-angle)]} {
                set ang [expr {-1.0*$optA(-angle)}]
                set val "rotate($ang $xbase,$ybase)"
                lappend attr "transform" $val
            }

            if {[string length $idAttr] > 0} {
                set attr [concat $attr $idAttr]
            }
            set attr [concat $attr [MakeAttrList \
              $type $opts $argsA(-usestyleattribute)]]
            set dy 0
            if {$nlines > 1} {
                
                # Use the 'tspan' trick here.
                set subList {}
                foreach line [split $chdata "\n"] {
                    lappend subList [MakeXMLList "tspan"  \
                      -attrlist [list "x" $xbase "dy" $dy] -chdata $line]
                    set dy $lineSpace
                }
                lappend xmlLL [MakeXMLList $elem -attrlist $attr \
                  -subtags $subList]
            } else {
                lappend xmlLL [MakeXMLList $elem -attrlist $attr \
                  -chdata $chdata]
            }
        }
        window {
            
            # There is no svg for this; must be handled by application layer.            
            #puts "window: $cmd"
            if {[string length $argsA(-windowitemhandler)]} {
                set xmllist \
                  [uplevel #0 $argsA(-windowitemhandler) [list $cmd] $args]
                if {[llength $xmllist]} {
                    lappend xmlLL $xmllist
                }
            }
        }
    }
    return $xmlLL
}

# can2svg::CoordsToAttr --
#
#       Makes a list of attributes corresponding to type and coords.
#       
# Arguments:
#
#       
# Results:
#       a list of attributes.

proc can2svg::CoordsToAttr {type coo opts svgElementVar} {
    upvar $svgElementVar elem 

    array set optA $opts
    
    # Figure out if we've got a spline.
    set haveSpline 0
    if {[info exists optA(-smooth)] && ($optA(-smooth) != "0") &&  \
      [info exists optA(-splinesteps)] && ($optA(-splinesteps) > 2)} {
        set haveSpline 1
    }
    set attr {}

    switch -- $type {
        arc {
            set elem "path"
            set data [MakeArcPath $coo $opts]
            set attr [list "d" $data]
        }
        bitmap - image {
            array set __optA $opts
            if {[info exists __optA(-image)]} {
                set elem "image"
                set attr [ImageCoordsToAttr $coo $opts]
            }
        }
        line {
            if {$haveSpline} {
                set elem "path"
                set data [ParseSplineToPath $type $coo]
                set attr [list "d" $data]
            } else {
                set elem "polyline"
                set attr [list "points" $coo]
            }   
        }
        oval {
            
            # Assume SVG ellipse.
            set elem "ellipse"
            foreach {x y w h} [NormalizeRectCoords $coo] break
            set attr [list  \
              "cx" [expr $x + $w/2.0] "cy" [expr $y + $h/2.0]  \
              "rx" [expr $w/2.0]      "ry" [expr $h/2.0]]
        }
        polygon {
            if {$haveSpline} {
                set elem "path"
                set data [ParseSplineToPath $type $coo]
                set attr [list "d" $data]
            } else {
                set elem "polygon"
                set attr [list "points" $coo]
            }
        }
        rectangle {
            set elem "rect"
            foreach {x y w h} [NormalizeRectCoords $coo] break
            set attr [list "x" $x "y" $y "width" $w "height" $h]
        }
        text {
            set elem "text"
            # ?
        }
    }
    return $attr
}

# can2svg::MakeArcPath --
# 
#       Makes a path using A commands from an arc.
#       Conversion from center to endpoint parameterization.
#       From: http://www.w3.org/TR/2003/REC-SVG11-20030114

proc can2svg::MakeArcPath {coo opts} {
    
    variable anglesToRadians
    variable pi

    # Canvas defaults.
    array set optA {
        -extent 90
        -start  0
        -style  pieslice
    }
    array set optA $opts

    # Extract center and radius from bounding box.
    foreach {x1 y1 x2 y2} $coo break
    set cx [expr ($x1 + $x2)/2.0]
    set cy [expr ($y1 + $y2)/2.0]
    set rx [expr abs($x1 - $x2)/2.0]
    set ry [expr abs($y1 - $y2)/2.0]

    set start  [expr $anglesToRadians * $optA(-start)]
    set extent [expr $anglesToRadians * $optA(-extent)]

    # NOTE: direction of angles are opposite for Tk and SVG!    
    set theta1 [expr -1*$start]
    set delta  [expr -1*$extent]
    set theta2 [expr $theta1 + $delta]
    set phi 0.0

    # F.6.4 Conversion from center to endpoint parameterization.
    set x1 [expr $cx + $rx * cos($theta1) * cos($phi) -  \
      $ry * sin($theta1) * sin($phi)]
    set y1 [expr $cy + $rx * cos($theta1) * sin($phi) +  \
      $ry * sin($theta1) * cos($phi)]
    set x2 [expr $cx + $rx * cos($theta2) * cos($phi) -  \
      $ry * sin($theta2) * sin($phi)]
    set y2 [expr $cy + $rx * cos($theta2) * sin($phi) +  \
      $ry * sin($theta2) * cos($phi)]
    
    set fa [expr {abs($delta) > $pi} ? 1 : 0]
    set fs [expr {$delta > 0.0} ? 1 : 0]
    
    set data [format "M %.1f %.1f A" $x1 $y1]
    append data [format " %.1f %.1f %.1f %1d %1d %.1f %.1f"  \
      $rx $ry $phi $fa $fs $x2 $y2]
    
    switch -- $optA(-style) {
        arc {
            # empty.
        }
        chord {
            append data " Z"
        }
        pieslice {
            append data [format " L %.1f %.1f Z" $cx $cy]
        }
    }
    return $data
}

# can2svg::MakeArcPathNonA --
# 
#       Makes a path without any A commands from an arc.

proc can2svg::MakeArcPathNonA {coo opts} {

    variable anglesToRadians

    array set optA $opts
    
    foreach {x1 y1 x2 y2} $coo break
    set cx [expr ($x1 + $x2)/2.0]
    set cy [expr ($y1 + $y2)/2.0]
    set rx [expr abs($x1 - $x2)/2.0]
    set ry [expr abs($y1 - $y2)/2.0]
    set rmin [expr $rx > $ry ? $ry : $rx]
    
    # This approximation gives a maximum half pixel error.
    set deltaPhi [expr 2.0/sqrt($rmin)]
    set extent   [expr $anglesToRadians * $optA(-extent)]
    set start    [expr $anglesToRadians * $optA(-start)]
    set nsteps   [expr int(abs($extent)/$deltaPhi) + 2]
    set delta    [expr $extent/$nsteps]
    set data [format "M %.1f %.1f L"  \
      [expr $cx + $rx*cos($start)] [expr $cy - $ry*sin($start)]]
    for {set i 0} {$i <= $nsteps} {incr i} {
        set phi [expr $start + $i * $delta]
        append data [format " %.1f %.1f"  \
          [expr $cx + $rx*cos($phi)] [expr $cy - $ry*sin($phi)]]
    }
    if {[info exists optA(-style)]} {
        
        switch -- $optA(-style) {
            chord {
                append data " Z"
            }
            pieslice {
                append data [format " %.1f %.1f Z" $cx $cy]
            }
        }
    } else {
        
        # Pieslice is the default.
        append data [format " %.1f %.1f Z" $cx $cy]
    }
    return $data
}

# can2svg::MakeAttrList --
# 
#       Handles the use of style attributes or presenetation attributes.

proc can2svg::MakeAttrList {type opts usestyleattribute} {
    
    if {$usestyleattribute} {
        set attrList [list style [MakeStyleAttr $type $opts]]
    } else {
        set attrList [MakeStyleList $type $opts]
    }
    return $attrList
}

# can2svg::MakeStyleAttr --
#
#       Produce the SVG style attribute from the canvas item options.
#
# Arguments:
#       type        tk canvas widget item type
#       opts
#       
# Results:
#       The SVG style attribute as a a string.

proc can2svg::MakeStyleAttr {type opts} {
    
    set style ""
    foreach {key value} [MakeStyleList $type $opts] {
        append style "${key}: ${value}; "
    }
    return [string trim $style]
}

proc can2svg::MakeStyleList {type opts args} {
    
    array set argsA {
        -setdefaults 1 
    }
    array set argsA $args
    
    # Defaults for everything except text.
    if {$argsA(-setdefaults) && ![string equal $type "text"]} {
        array set styleArr {fill none stroke black}
    }
    set fillCol black
    
    foreach {key value} $opts {
        
        switch -- $key {
            -arrow {
                set arrowValue $value
            }
            -arrowshape {
                set arrowShape $value
            }
            -capstyle {
                if {[string equal $value "projecting"]} {
                    set value "square"
                }
                if {![string equal $value "butt"]} {
                    set styleArr(stroke-linecap) $value
                }
            }
            -dash {
                set dashValue $value
            }
            -dashoffset {
                if {$value != 0} {
                    set styleArr(stroke-dashoffset) $value
                }
            }
            -extent {
                # empty
            }
            -fill {
                
                # Need to translate names to hex spec.
                if {![regexp {#[0-9]+} $value]} {
                    set value [FormatColorName $value]
                }
                set fillCol $value                
                if {[string equal $type "line"]} {
                    set styleArr(stroke) [MapEmptyToNone $value]
                } else {
                    set styleArr(fill) [MapEmptyToNone $value]
                }
            }
            -font {
                array set styleArr [MakeFontStyleList $value]
                
            }
            -joinstyle {
                set styleArr(stroke-linejoin) $value                
            }
            -outline {
                set styleArr(stroke) [MapEmptyToNone $value]
            }
            -outlinestipple {
                set outlineStippleValue $value
            }
            -start {
                # empty
            }
            -stipple {
                set stippleValue $value
            }
            -width {
                set styleArr(stroke-width) $value
            }
        }
    }
    
    # If any arrow specify its marker def url key.
    if {[info exists arrowValue]} {
        if {[info exists arrowShape]} {        
            foreach {a b c} $arrowShape break
            set arrowIdKey "arrowMarkerDef_${fillCol}_${a}_${b}_${c}"
            set arrowIdKeyLast "arrowMarkerLastDef_${fillCol}_${a}_${b}_${c}"
        } else {
            set arrowIdKey "arrowMarkerDef_${fillCol}"
            set arrowIdKeyLast $arrowIdKey
        }
        
        switch -- $arrowValue {
            first {
                set styleArr(marker-start) "url(#$arrowIdKey)"
            }
            last {
                set styleArr(marker-end) "url(#$arrowIdKeyLast)"
            }
            both {
                set styleArr(marker-start) "url(#$arrowIdKey)"
                set styleArr(marker-end) "url(#$arrowIdKeyLast)"
            }
        }
    }
    
    if {[info exists stippleValue]} {
        
        # Overwrite any existing.
        set styleArr(fill) "url(#tile[string trimleft $stippleValue @])"
    }
    if {[info exists outlineStippleValue]} {
        
        # Overwrite any existing.
        set styleArr(stroke) "url(#tile[string trimleft $stippleValue @])"
    }
    
    # Transform dash value.
    if {[info exists dashValue]} {
                
        # Two different syntax here.                
        if {[regexp {[\.,\-_]} $dashValue]} {
            
            # .=2 ,=4 -=6 space=4    times stroke width.
            # A space enlarges the... space.
            # Not foolproof!
            regsub -all -- {[^ ]} $dashValue "& " dash
            regsub -all -- "   "  $dash  "12 " dash
            regsub -all -- "  "   $dash  "8 " dash
            regsub -all -- " "    $dash  "4 " dash
            regsub -all -- {\.}   $dash  "2 " dash
            regsub -all -- {,}    $dash  "4 " dash
            regsub -all -- {-}    $dash  "6 " dash                    
        
            # Multiply with stroke width if > 1.
            if {[info exists styleArr(stroke-width)] &&  \
              ($styleArr(stroke-width) > 1)} {
                set width $styleArr(stroke-width)
                set dashOrig $dash
                set dash {}
                foreach num $dashOrig {
                    lappend dash [expr int($width * $num)]
                }
            }
            set styleArr(stroke-dasharray) [string trim $dash]
        } else {
            set dashValue [string trim $dashValue]
            if {$dashValue ne ""} {
                set styleArr(stroke-dasharray) $dashValue
            }
        }
    }
    if {[string equal $type "polygon"]} {
        set styleArr(fill-rule) "evenodd"
    }        
    return [array get styleArr]
}

proc can2svg::FormatColorName {value} {

    if {[string length $value] == 0} {
        return $value
    }

    switch -- $value {
        black - white - red - green - blue {
            set col $value
        }
        default {
        
            # winfo rgb . white -> 65535 65535 65535
            foreach rgb [winfo rgb . $value] {
                lappend rgbx [expr $rgb >> 8]
            }
            set col [eval {format "#%02x%02x%02x"} $rgbx]
        }
    }
    return $col
}

# can2svg::MakeFontStyleList --
# 
#       Takes a tk font description and returns a flat style array.
#       
# Arguments:
#       fontDesc    a tk font description 
#       
# Results:
#       flat style array

proc can2svg::MakeFontStyleList {fontDesc} {    

    # MICK Modify - break a named font into its component fields
    set font [lindex $fontDesc 0]
    if {[lsearch -exact [font names] $font] > -1} {
        
        # This is a font name
        set styleArr(font-family) [font config $font -family]
        set fsize [font config $font -size]
        if {$fsize > 0} {
            # points
            set funit pt
        } else {
            # pixels (actually user units)
            set funit px
        }        
        set styleArr(font-size) "[expr abs($fsize)]$funit"
        if {[font config $font -slant] == "italic"} {
            set styleArr(font-style) italic
        }
        if {[font config $font -weight] == "bold"} {
            set styleArr(font-weight) bold
        }
        if {[font config $font -underline]} {
            set styleArr(text-decoration) underline
        }
        if {[font config $font -overstrike]} {
            set styleArr(text-decoration) overline
        }
    } else {
        set styleArr(font-family) [lindex $fontDesc 0]
        if {[llength $fontDesc] > 1} {
            # Mick: added pt at end
            set fsize [lindex $fontDesc 1]
            if {$fsize > 0} {
                # points
                set funit pt
            } else {
                # pixels (actually user units)
                set funit px
            }
            set styleArr(font-size) "[expr abs($fsize)]$funit"
        }
        if {[llength $fontDesc] > 2} {
            set tkstyle [lindex $fontDesc 2]
            switch -- $tkstyle {
                bold {
                    set styleArr(font-weight) $tkstyle
                }
                italic {
                    set styleArr(font-style) $tkstyle
                }
                underline {
                    set styleArr(text-decoration) underline
                }
                overstrike {
                    set styleArr(text-decoration) overline
                }
            }
        }                
    }
    return [array get styleArr]
}

# can2svg::SplitWrappedLines --
# 
# MICK O'DONNELL: added code to split wrapped lines
# This is actally only needed for text items with -width != 0.
# If -width = 0 then just return it.

proc can2svg::SplitWrappedLines {line font wgtWidth} {

     # If the text is shorter than the widget width, no need to wrap
     # If the wgtWidth comes out as 0, don't wrap
     if {$wgtWidth == 0 || [font measure $font $line] <= $wgtWidth} {
        return [list $line]
     }

     # Wrap the line
     set width 
     set endchar 0
     while {$width < $wgtWidth} {
        set substr [string range $line 0 [incr endchar]]
        set width [font measure $font $substr]
     }

     # Go back till we find a nonwhite char
     set char [string index $line $endchar]
     set default [expr $endchar -1]
     while {[BreakChar $char] == 0} {
        if {$endchar == 0} {
            # we got to the front without breaking, so break midword
            set endchar $default
            break
        }
        set char [string index $line [incr endchar -1]]
     }
     set first [string range $line 0 $endchar]
     set rest [string range $line [expr $endchar+1] end]
     return [concat [list $first] [SplitWrappedLines $rest $font $wgtWidth]]
}

proc can2svg::BreakChar {char} {
     if [string is space $char] {return 1}
     if {$char == "-"} {return 1}
     if {$char == ","} {return 1}
     return 0
}

# can2svg::MakeImageAttr --
#
#       Special code is needed to make the attributes for an image item.
#       
# Arguments:
#       elem 
#       
# Results:
#   

proc can2svg::MakeImageAttr {coo opts args} {
    variable confopts
    
    array set optA {-anchor nw}
    array set optA $opts
    array set argsA $args
    
    set attrList [ImageCoordsToAttr $coo $opts]

    # We should make this an URI.
    set image $optA(-image)
    set fileName [$image cget -file]
    if {$fileName ne ""} {
#        if {[string equal $argsA(-uritype) "file"]} {
#            set uri [FileUriFromLocalFile $fileName]
#        } elseif {[string equal $argsA(-uritype) "http"]} {
#            set uri [HttpFromLocalFile $fileName]
#        }
        lappend attrList "xlink:href" $uri
    } else {
        # Unclear if we can use base64 data in svg.
    }    
    return $attrList
}

# Function � �: can2svg::ImageCoordsToAttr 
# ------------------------------ ------------------------------ --------- 
# Returns � � : list of x y width and height including description 
# Parameters �: coo �- coordinates of the image 
# � � � � � � � opts - argument list -anchor nw ... 
#
# Description : 
# fixme (Roger) 01/25/2008 :Why not using the bounding box? 
#
# Written � � : 2002-2007, Mats 
# Rewritten � : 01/25/2008, Roger 
# ------------------------------ ------------------------------ --------- 

proc can2svg::ImageCoordsToAttr {coo opts} { 
    
    array set optArr {-anchor nw}
    array set optArr $opts
    
    if {![info exists optArr(-image)]} { 
        return -code error "Missing -image option; can't parse that" 
    } 
    set theImage $optArr(-image) 

    lassign $coo x0 y0
    set w [image width $theImage]
    set h [image height $theImage]
    
    set x [expr {$x0 - $w/2.0}] 
    set y [expr {$y0 - $h/2.0}] 

    if { "center" ne $optArr(-anchor) } { 
        foreach orientation [split $optArr(-anchor) {}] { 
            switch $orientation { 
                n { set y $y0 } 
                s { set y [expr {$y0 - $w}] } 
                e { set x [expr {$x0 - $h}] } 
                w { set x $x0 } 
                default {} 
            } 
        } 
    } 
    return [list "x" $x "y" $y "width" $w "height" $h] 
}

proc can2svg::ImageCoordsToAttrBU {coo opts} {
    array set optA {-anchor nw}
    array set optA $opts
    if {[info exists optA(-image)]} {
        set theImage $optA(-image)
        set w [image width $theImage]
        set h [image height $theImage]
    } else {
        return -code error "Missing -image option; can't parse that"
    }
    foreach {x0 y0} $coo break
    
    switch -- $optA(-anchor) {
        nw {
            set x $x0
            set y $y0
        }
        n {
            set x [expr $x0 - $w/2.0]
            set y $y0
        }
        ne {
            set x [expr $x0 - $w]
            set y $y0
        }
        e {
            set x $x0
            set y [expr $y0 - $h/2.0]
        }
        se {
            set x [expr $x0 - $w]
            set y [expr $y0 - $h]
        }
        s {
            set x [expr $x0 - $w/2.0]
            set y [expr $y0 - $h]
        }
        sw {
            set x $x0
            set y [expr $y0 - $h]
        } 
        w {
            set x $x0
            set y [expr $y0 - $h/2.0]
        }
        center {
            set x [expr $x0 - $w/2.0]
            set y [expr $y0 - $h/2.0]
        }
    }
    set attrList [list "x" $x "y" $y "width" $w "height" $h]
    return $attrList
}

# can2svg::GetTextSVGCoords --
# 
#       Figure out the baseline coords of the svg text element from
#       the canvas text item.
#
# Arguments:
#       coo         {x y}
#       anchor
#       chdata      character data, newlines included.
#       
# Results:
#       raw xml data of the marker def element.

proc can2svg::GetTextSVGCoords {coo anchor chdata theFont nlines} {
    
    foreach {x y} $coo break
    set ascent [font metrics $theFont -ascent]
    set lineSpace [font metrics $theFont -linespace]

    # If not anchored to the west it gets more complicated.
    if {![string match $anchor "*w*"]} {
        
        # Need to figure out the extent of the text.
        if {$nlines <= 1} {
            set textWidth [font measure $theFont $chdata]
        } else {
            set textWidth 0
            foreach line [split $chdata "\n"] {
                set lineWidth [font measure $theFont $line]
                if {$lineWidth > $textWidth} {
                    set textWidth $lineWidth
                }
            }
        }
    }
    
    switch -- $anchor {
        nw {
            set xbase $x
            set ybase [expr $y + $ascent]
        }
        w {
            set xbase $x
            set ybase [expr $y - $nlines*$lineSpace/2.0 + $ascent]
        }
        sw {
            set xbase $x
            set ybase [expr $y - $nlines*$lineSpace + $ascent]
        }
        s {
            set xbase [expr $x - $textWidth/2.0]
            set ybase [expr $y - $nlines*$lineSpace + $ascent]
        }
        se {
            set xbase [expr $x - $textWidth]
            set ybase [expr $y - $nlines*$lineSpace + $ascent]
        }
        e {
            set xbase [expr $x - $textWidth]
            set ybase [expr $y - $nlines*$lineSpace/2.0 + $ascent]
        }
        ne {
            set xbase [expr $x - $textWidth]
            set ybase [expr $y + $ascent]
        } 
        n {
            set xbase [expr $x - $textWidth/2.0]
            set ybase [expr $y + $ascent]
        }
        center {
            set xbase [expr $x - $textWidth/2.0]
            set ybase [expr $y - $nlines*$lineSpace/2.0 + $ascent]
        }
    }
    
    return [list $xbase $ybase]
}

# can2svg::ParseSplineToPath --
# 
#       Make the path data string for a bezier.
#
# Arguments:
#       type        canvas type: line or polygon
#       coo         its coordinate list
#       
# Results:
#       path data string

proc can2svg::ParseSplineToPath {type coo} {
    
    set npts [expr [llength $coo]/2]
    
    # line is open ended while the polygon must be closed.
    # Need to construct a closed smooth polygon with path instructions.

    switch -- $npts {
        1 {
            set data "M [lrange $coo 0 1]"
        }
        2 {
            set data "M [lrange $coo 0 1] L [lrange $coo 2 3]"                                
        }
        3 {
            set data "M [lrange $coo 0 1] Q [lrange $coo 2 5]"
        }
        default {
            if {[string equal $type "polygon"]} {
                set x0s [expr ([lindex $coo 0] + [lindex $coo end-1])/2.]
                set y0s [expr ([lindex $coo 1] + [lindex $coo end])/2.]
                set data "M $x0s $y0s"
                    
                # Add Q1 and Q2 points.
                append data " Q [lrange $coo 0 1]"
                set x0 [expr ([lindex $coo 0] + [lindex $coo 2])/2.]
                set y0 [expr ([lindex $coo 1] + [lindex $coo 3])/2.]
                append data " $x0 $y0"
                set xctrlp [lindex $coo 2]
                set yctrlp [lindex $coo 3]
                set tind 4
            } else {
                set data "M [lrange $coo 0 1]"
                    
                # Add Q1 and Q2 points.
                append data " Q [lrange $coo 2 3]"
                set x0 [expr ([lindex $coo 2] + [lindex $coo 4])/2.]
                set y0 [expr ([lindex $coo 3] + [lindex $coo 5])/2.]
                append data " $x0 $y0"
                set xctrlp [lindex $coo 4]
                set yctrlp [lindex $coo 5]
                set tind 6
            }
            append data " T"                                
            foreach {x y} [lrange $coo $tind end-2] {
                #puts "x=$x, y=$y, xctrlp=$xctrlp, yctrlp=$yctrlp"
                
                # The T point is the midpoint between the
                # two control points.
                set x0 [expr ($x + $xctrlp)/2.0]
                set y0 [expr ($y + $yctrlp)/2.0]
                set xctrlp $x
                set yctrlp $y
                append data " $x0 $y0"
                #puts "data=$data"
            }
            if {[string equal $type "polygon"]} {
                set x0 [expr ([lindex $coo end-1] + $xctrlp)/2.0]
                set y0 [expr ([lindex $coo end] + $yctrlp)/2.0]
                append data " $x0 $y0"
                append data " $x0s $y0s"
            } else {
                append data " [lrange $coo end-1 end]"
            }
            #puts "data=$data"
        }
    }
    return $data
}

# can2svg::MakeArrowMarker --
# 
#       Make the xml for an arrow marker def element.
#
# Arguments:
#       a           arrows length along its symmetry line
#       b           arrows total length
#       c           arrows half width
#       col         its color
#       
# Results:
#       a list of xmllists of the marker def elements, both start and last.

proc can2svg::MakeArrowMarker {a b c col} {
    
    variable formatArrowMarker
    variable formatArrowMarkerLast
    
    unset -nocomplain formatArrowMarker
    
    if {![info exists formatArrowMarker]} {
        
        # "M 0 c, b 0, a c, b 2*c Z" for the start marker.
        # "M 0 0, b c, 0 2*c, b-a c Z" for the last marker.
        set data "M 0 %s, %s 0, %s %s, %s %s Z"
        set style "fill: %s; stroke: %s;"
        set attr [list "d" $data "style" $style]
        set arrowList [MakeXMLList "path" -attrlist $attr]
        set markerAttr [list "id" %s "markerWidth" %s "markerHeight" %s  \
          "refX" %s "refY" %s "orient" "auto"]
        set defElemList [MakeXMLList "defs" -subtags  \
          [list [MakeXMLList "marker" -attrlist $markerAttr \
          -subtags [list $arrowList] ] ] ]
        set formatArrowMarker $defElemList
        
        # ...and the last arrow marker.
        set dataLast "M 0 0, %s %s, 0 %s, %s %s Z"
        set attrLast [list "d" $dataLast "style" $style]
        set arrowLastList [MakeXMLList "path" -attrlist $attrLast]
        set defElemLastList [MakeXMLList "defs" -subtags  \
          [list [MakeXMLList "marker" -attrlist $markerAttr \
          -subtags [list $arrowLastList] ] ] ]
        set formatArrowMarkerLast $defElemLastList
    }
    set idKey "arrowMarkerDef_${col}_${a}_${b}_${c}"
    set idKeyLast "arrowMarkerLastDef_${col}_${a}_${b}_${c}"
    
    # Figure out the order of all %s substitutions.
    set markerXML [format $formatArrowMarker $idKey  \
      $b [expr 2*$c] 0 $c  \
      $c $b $a $c $b [expr 2*$c] $col $col]
    set markerLastXML [format $formatArrowMarkerLast $idKeyLast  \
      $b [expr 2*$c] $b $c \
      $b $c [expr 2*$c] [expr $b-$a] $c $col $col]
    
    return [list $markerXML $markerLastXML]
}

# can2svg::MakeGrayStippleDef --
#
#

proc can2svg::MakeGrayStippleDef {stipple} {
    
    variable stippleDataArr
    
    set pathList [MakeXMLList "path" -attrlist  \
      [list "d" $stippleDataArr($stipple) "style" "stroke: black; fill: none;"]]
    set patterAttr [list "id" "tile$stipple" "x" 0 "y" 0 "width" 4 "height" 4 \
      "patternUnits" "userSpaceOnUse"]
    set defElemList [MakeXMLList "defs" -subtags  \
      [list [MakeXMLList "pattern" -attrlist $patterAttr \
      -subtags [list $pathList] ] ] ]
    
    return $defElemList
}

# can2svg::MapEmptyToNone --
#
#
# Arguments:
#       elem 
#       
# Results:
#   

proc can2svg::MapEmptyToNone {val} {

    if {[string length $val] == 0} {
        return "none"
    } else {
        return $val
    }
}

# can2svg::NormalizeRectCoords --
#
#
# Arguments:
#       elem 
#       
# Results:
#   

proc can2svg::NormalizeRectCoords {coo} {
    
    foreach {x1 y1 x2 y2} $coo {}
    return [list [expr $x2 > $x1 ? $x1 : $x2]  \
      [expr $y2 > $y1 ? $y1 : $y2]  \
      [expr abs($x1-$x2)]  \
      [expr abs($y1-$y2)]]
}

# can2svg::makedocument --
#
#       Adds the prefix and suffix elements to make a complete XML/SVG
#       document.
#
# Arguments:
#       elem 
#       
# Results:
#   

proc can2svg::makedocument {width height xml} {
    
    set pre "<?xml version='1.0'?>\n\
      <!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.1//EN\"\
      \"Graphics/SVG/1.1/DTD/svg11.dtd\">"
    #set svgStart "<svg width='$width' height='$height' version='1.1' xmlns='http://www.w3.org/2000/svg' xmlns:xlink='http://www.w3.org/1999/xlink'>"
    set w [expr int($width * .75)]
    set h [expr int($height * .75)]
    set svgStart "<svg width='${w}pt' height='${h}pt' viewBox=\"0 0 $width $height\" version='1.1' xmlns='http://www.w3.org/2000/svg' xmlns:xlink='http://www.w3.org/1999/xlink'>"

#<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="428pt" height="737pt" viewBox="0 0 428 737" version="1.2">

    set svgEnd "</svg>"
    return "${pre}\n${svgStart}\n${xml}${svgEnd}"
}

# can2svg::canvas2file --
#
#       Takes everything on a canvas widget, translates it to XML/SVG,
#       and puts it on a file.
#       
# Arguments:
#       wcan        the canvas widget path
#       path        the file path
#       args:   -height
#               -width 
#       
# Results:
#   

proc can2svg::canvas2file {wcan path args} {
    variable confopts
    variable defsArrowMarkerArr
    variable defsStipplePatternArr
    
    array set argsA [array get confopts]
    set x 0
    set y 0
    #set width "100%"
    #set height "100%"
    set width [winfo width $wcan]
    set height [winfo height $wcan]
    foreach {x y width height} [$wcan cget -scrollregion] break
    array set argsA [list -width $width -height $height]
    array set argsA $args
    set args [array get argsA]
    
    # Need to make a fresh start for marker def's.
    unset -nocomplain defsArrowMarkerArr defsStipplePatternArr
  
    set fd [open $path w]

    # This could have been done line by line.
    set xml ""
    foreach id [$wcan find all] {
        set type [$wcan type $id]
        set opts [$wcan itemconfigure $id]
        set opcmd {}
        foreach opt $opts {
            set op [lindex $opt 0]
            set val [lindex $opt 4]
            
            # Empty val's except -fill can be stripped off.
            if {![string equal $op "-fill"] && ([string length $val] == 0)} {
                continue
            }
            lappend opcmd $op $val
        }
        set co [$wcan coords $id]
        set cmd [concat "create" $type $co $opcmd]
        append xml "\t[eval {can2svg $cmd} $args]\n"        
    }
    puts $fd [makedocument $argsA(-width) $argsA(-height) $xml]
    close $fd
}

# can2svg::MakeXML --
#
#       Creates raw xml data from a hierarchical list of xml code.
#       This proc gets called recursively for each child.
#       It makes also internal entity replacements on character data.
#       Mixed elements aren't treated correctly generally.
#       
# Arguments:
#       xmlList     a list of xml code in the format described in the header.
#       
# Results:
#       raw xml data.

proc can2svg::MakeXML {xmlList} {
        
    # Extract the XML data items.
    foreach {tag attrlist isempty chdata childlist} $xmlList {}
    set rawxml "<$tag"
    foreach {attr value} $attrlist {
        append rawxml " ${attr}='${value}'"
    }
    if {$isempty} {
        append rawxml "/>"
        return $rawxml
    } else {
        append rawxml ">"
    }
    
    # Call ourselves recursively for each child element. 
    # There is an arbitrary choice here where childs are put before PCDATA.
    foreach child $childlist {
        append rawxml [MakeXML $child]
    }
    
    # Make standard entity replacements.
    if {[string length $chdata]} {
        append rawxml [XMLCrypt $chdata]
    }
    append rawxml "</$tag>"
    return $rawxml
}

# can2svg::MakeXMLList --
#
#       Build an element list given the tag and the args.
#
# Arguments:
#       tagname:    the name of this element.
#       args:       
#           -empty   0|1      Is this an empty tag? If $chdata 
#                             and $subtags are empty, then whether 
#                             to make the tag empty or not is decided 
#                             here. (default: 1)
#            -attrlist {attr1 value1 attr2 value2 ..}   Vars is a list 
#                             consisting of attr/value pairs, as shown.
#            -chdata $chdata   ChData of tag (default: "").
#            -subtags {$subchilds $subchilds ...} is a list containing xmldata
#                             of $tagname's subtags. (default: no sub-tags)
#       
# Results:
#       a list suitable for can2svg::MakeXML.

proc can2svg::MakeXMLList {tagname args} {
        
    # Fill in the defaults.
    array set xmlarr {-isempty 1 -attrlist {} -chdata {} -subtags {}}
    
    # Override the defults with actual values.
    if {[llength $args] > 0} {
        array set xmlarr $args
    }
    if {!(($xmlarr(-chdata) eq "") && ($xmlarr(-subtags) eq ""))} {
        set xmlarr(-isempty) 0
    }
    
    # Build sub elements list.
    set sublist [list]
    foreach child $xmlarr(-subtags) {
        lappend sublist $child
    }
    set xmlList [list $tagname $xmlarr(-attrlist) $xmlarr(-isempty)  \
      $xmlarr(-chdata) $sublist]
    return $xmlList
}

# can2svg::XMLCrypt --
#
#       Makes standard XML entity replacements.
#
# Arguments:
#       chdata:     character data.
#       
# Results:
#       chdata with XML standard entities replaced.

proc can2svg::XMLCrypt {chdata} {

    foreach from {\& < > {"} {'}}   \
      to {{\&amp;} {\&lt;} {\&gt;} {\&quot;} {\&apos;}} {
        regsub -all $from $chdata $to chdata
    }
# "'
    return $chdata
}

# can2svg::FileUriFromLocalFile --
#
#       Not foolproof!

#proc can2svg::FileUriFromLocalFile {path} {
#        
#    # Quote the disallowed characters according to the RFC for URN scheme.
#    # ref: RFC2141 sec2.2
#    return file://[uriencode::quotepath $path]
#}

# can2svg::HttpFromLocalFile --
#
#       Translates an absolute file path to an uri encoded http address.

#proc can2svg::HttpFromLocalFile {path} {
#    variable confopts
#    
#    set relPath [::tfileutils::relative $confopts(-httpbasedir) $path]
#    set relPath [uriencode::quotepath $relPath]
#    return "http://$confopts(-httpaddr)/$relPath"
#}

#-------------------------------------------------------------------------------
