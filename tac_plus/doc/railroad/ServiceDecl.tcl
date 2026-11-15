# ServiceDecl
set all_graphs {
  tac_plus/ServiceDecl
  {line
    'service '= serviceName
    {optx
      '@ hostName
    }
    {optx
      '{
      {loop
        {
        }
        ServiceAttr
      }
      '}
    }
  }
}
