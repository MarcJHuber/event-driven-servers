# Config
set all_graphs {
  tcprelay/Config
  {stack
    {line
      'id '= 'tcprelay
    }
    {line
      '{
      {toploop
        {or
          {line
            'tls
            {or
              {line
                'cert-file '= certFile
              }
              {line
                'key-file '= keyFile
              }
              {line
                'passphrase '= passPhrase
              }
            }
          }
          {line
            'rebalance '= number
          }
          {line
            'idle 'timeout '= seconds
          }
          {line
            'retire 'limit '= number
          }
          {line
            'remote '= '{
            {or
              {line
                'address '= ipAddress
              }
              {line
                'port '= tcpPort
              }
              {line
                'weight '= number
              }
            }
            '}
          }
          {line
            'local 'address '= ipAddress
          }
          {line
            SyslogDecl
          }
        }
      }
      '}
    }
  }
}
