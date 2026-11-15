# ChildDecl
set all_graphs {
  spawnd/ChildDecl
  {line
    'spawn '{
    {toploop
      {or
        {line
          'exec '= pathToExecutable
        }
        {line
          'id '= subIdentifier
        }
        {line
          'config '= pathToConfig
        }
        {line
          'instances
          {or
            'min 'max
          }
          '=
          number
        }
        {line
          'users
          {or
            'min 'max
          }
          '=
          number
        }
        {line
          'userid '= uidNumber
        }
        {line
          'groupid '= gidNumber
        }
        {line
          'sticky 'cache
          {or
            {line
              'timeout '= number
            }
            {line
              'sticky 'cache 'period '= seconds
            }
          }
        }
        {line
          'ipc 'key '= number
        }
      }
    }
    '}
  }
}
