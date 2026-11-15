# PAMConf
set all_graphs {
  mavis/PAMConf
  {stack
    {line
      'mavis 'module '= 'pam
    }
    {line
      '{
      {toploop
        {or
          {line
            'chroot '=
            {or
              'yes 'no
            }
          }
          {line
            'service '= string
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
