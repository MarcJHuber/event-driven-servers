# AnonftpConf
set all_graphs {
  mavis/AnonftpConf
  {stack
    {line
      'mavis 'module '= 'anonftp
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
            'root '= rootDirectory
          }
          {loop
            {line
              'upload '= uploadPath
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
