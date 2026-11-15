# CacheConf
set all_graphs {
  mavis/CacheConf
  {stack
    {line
      'mavis 'module '= 'cache
    }
    {line
      '{
      {toploop
        {or
          {line
            'purge 'period '= seconds
          }
          {line
            'expire
            {optx
              'FTP
            }
            '= seconds
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
