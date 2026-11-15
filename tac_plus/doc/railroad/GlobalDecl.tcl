# GlobalDecl
set all_graphs {
  tac_plus/GlobalDecl
  {or
    {line
      'umask '= umask
    }
    {line
      'syslog
      {or
        'facility 'severity
      }
      '= string
    }
    {line
      'userid '= userID
    }
    {line
      'groupid '= groupID
    }
    {line
      'working 'directory '= directory
    }
    {line
      'coredump 'directory '= directory
    }
    {line
      'retire
      {or
        {line
          'limit '= count
        }
        {line
          'seconds '= seconds
        }
      }
    }
    {line
      'time 'zone '= timeZone
    }
    {line
      'dns
      {or
        {line
          'cleanup 'period '= seconds
        }
        {line
          {optx
            'prefetch
          }
          'address CIDR '= string
        }
        {line
          'prefetch 'file '= fileName
        }
      }
    }
    {line
      'default 'realm '= realmName
    }
    {line
      'accept 'haproxy '=
      {or
        'yes 'no
      }
    }
  }
}
