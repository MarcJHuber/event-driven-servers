# ExternalConf
set all_graphs {
  mavis/ExternalConf
  {stack
    {line
      'mavis 'module '= 'external
    }
    {line
      '{
      {toploop
        {or
          {line
            'user-id '= usernameOrUID
          }
          {line
            'group-id '= groupnameOrUID
          }
          {line
            'home '= homeDirectory
          }
          {line
            'childs
            {or
              'min 'max
            }
            '= number
          }
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
