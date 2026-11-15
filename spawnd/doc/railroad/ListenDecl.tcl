# ListenDecl
set all_graphs {
  spawnd/ListenDecl
  {line
    'listen '{
    {toploop
      {or
        {line
          'address '= ipAddress
        }
        {line
          'port '= tcpPort
        }
        {line
          'path '= path
        }
        {line
          'userid '= userID
        }
        {line
          'groupid '= groupID
        }
        {line
          'tls '=
          {or
            'yes 'no
          }
        }
        {line
          'haproxy '=
          {or
            'yes 'no
          }
        }
        {line
          'protocol '=
          {or
            'TCP 'UDP
          }
        }
        {line
          'flag '=
          {or
            'access 'accounting
          }
        }
        {line
          'bind 'retry 'delay '= seconds
        }
        {line
          'backlog '= number
        }
        {line
          'tcp 'keepalive 
          {or
            'idle 'interval 'count
          } '= number
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
          'dscp '= dscpValue
        }
        
      }
    }
    '}
  }
}
