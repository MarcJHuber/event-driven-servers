# PassiveExpr
set all_graphs {
  ftpd/PassiveExpr
  {line
    'passive
    {or
      {line
        'address
        {optx
          Acl
        }
        '= ipAdress
      }
      {line
        'port
        {or
          'min 'max
        }
        Acl '= portNumber
      }
    }
  }
}
