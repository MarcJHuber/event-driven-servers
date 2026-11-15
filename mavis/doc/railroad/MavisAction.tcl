# MavisAction
set all_graphs {
  mavis/MavisAction
  {toploop
    {or
      {line
        'continue
      }
      {line
        'return
      }
      {line
        'skip
      }
      {line
        'if MavisCond MavisAction
        {optx
          'else MavisAction
        }
      }
      {line
        'set MavisAttribute '= value
      }
      {line
        'unset MavisAttribute
      }
      {line
        'toupper MavisAttribute
      }
      {line
        'tolower MavisAttribute
      }
      {line
        '{
        {loop
          MavisAction
        }
        '}
      }
    }
  }
}
