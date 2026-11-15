# MavisDecl
set all_graphs {
  mavis/MavisDecl
  {line
    'mavis
    {or
      {line
        'module
        {optx
          identitySourceName
        }
        '= moduleName '{ moduleConfig '}
      }
      {line
        'path '= path
      }
    }
  }
}
