# RemoteConf
set all_graphs {
  mavis/RemoteConf
  {stack
    {line
      'mavis 'module '= 'remote
    }
    {line
      '{
      {toploop
        {or
          {line
            'local 'address '= ipAddress
          }
          {line
            'rebalance '= number
          }
          {line
            'timeout '= seconds
          }
          {line
            'tries '= number
          }
          {line
            'dst '= '{
            {toploop
              {or
                {line
                  'path '= unixPath
                }
                {or
                  {line
                    'address '= ipAddress
                  }
                  {line
                    'port '= port
                  }
                }
                {line
                  'blowfish
                  {or
                    {line
                      'key '= key
                    }
                    {line
                      'keyfile '= keyFile
                    }
                  }
                }
                {line
                  'script
                  {or
                    'in 'out
                  }
                  '= '{ MavisAction '}
                }
              }
            }
            '}
          }
          {line
            'script
            {or
              'in 'out
            }
            '= '{ MavisAction '}
          }
          {line
            'action
            {or
              'error
              'not-found
            }
            '=
            {or
              'continue
              'reject
            }
          }
        }
      }
      '}
    }
  }
}
