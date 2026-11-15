# TeeConf
set all_graphs {
  mavis/TeeConf
  {stack
    {line
      'mavis 'module '= 'tee
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
            'path
            {optx
              {or
                'in 'out
              }
            }
            '= file
          }
          {line
            'mode '= octalMask
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
