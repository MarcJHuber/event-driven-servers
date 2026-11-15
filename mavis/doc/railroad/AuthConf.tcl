# AuthConf
set all_graphs {
  mavis/AuthConf
  {stack
    {line
      'mavis 'module '= 'auth
    }
    {line
      '{
      {toploop
        {or
          {line
            'authmode '=
            {or
              'required 'sufficient
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
