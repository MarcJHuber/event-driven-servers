# RealmAttr
set all_graphs {
  tac_plus/RealmAttr
  {or
    {line
      MavisDecl
    }
    {line
      LogDecl
    }
    {line
      HostDecl
    }
    {line
      GroupDecl
    }
    {line
      UserDecl
    }
    {line
      {or
        'authentication 'authorization 'accounting
      }
      'log '=
      {or
        fileName logName 'syslog
      }
    }
    {line
      'connection 'timeout '= seconds
    }
    {line
      'context 'timeout '= seconds
    }
    {line
      'warning 'period '= days
    }
    {line
      'single-connect '=
      {or
        'yes 'no
      }
    }
    {line
      'dns
      {or
        {line
          'reverse-lookup '=
          {or
            'yes 'no
          }
        }
        {line
          'timeout '= seconds
        }
      }
    }
    {line
      'skip
      {or
        'conflicting 'missing
      }
      'groups '=
      {or
        'yes 'no
      }
    }
    {line
      'mavis 'cache 'timeout '= seconds
    }
    {line
      'date 'format '= string
    }
    {line
      'log 'separator '= string
    }
    {line
      'client 'realm '= realmName
    }
    {line
      RealmAttrAuthen
    }
    {line
      Debug
    }
  }
}
