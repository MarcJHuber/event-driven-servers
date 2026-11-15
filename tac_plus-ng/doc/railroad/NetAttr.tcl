# HostAttr
set all_graphs {
  tac_plus-ng/NetAttr
  {or
    {line
      'address
      { or
        {line
          '= CIDR
        }
        {line
          'file '= filePath
        }
      }
    }
    {line
      'parent '= netName
    }
    NetDecl
  }
}
