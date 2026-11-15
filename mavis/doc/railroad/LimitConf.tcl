# LimitConf
set all_graphs {
  mavis/LimitConf
  {stack
    {line
      'mavis 'module '= 'limit
    }
    {line
      '{
      {toploop
        {or
          {line
            'purge 'period '= seconds
          }
          {line
            'blacklist
            {or
              {line
                'time '= seconds
              }
              {line
                'count '= number
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
