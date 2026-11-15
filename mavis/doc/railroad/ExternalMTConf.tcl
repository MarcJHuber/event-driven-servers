# ExternalConf
set all_graphs {
  mavis/ExternalConf
  {stack
    {line
      'mavis 'module '= 'external-mt
    }
    {line
      '{
      {toploop
        {or
          {line
            'setenv name '= value
          }
          {line
            'exec '= execFile
            {optx
              {toploop
                {line
                  '" argument '"
                }
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
