# ServiceDecl
set all_graphs {
  tac_plus-ng/ServiceDecl
  {line
    'service '= serviceName
    {optx
      '@ deviceName
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
