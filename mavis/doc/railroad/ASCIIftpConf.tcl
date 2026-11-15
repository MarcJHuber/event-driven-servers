# ASCIIftpConf
set all_graphs {
  mavis/ASCIIftpConf
  {stack
    {line
      'mavis 'module '= 'asciiftp
    }
    {line
      '{
      {toploop
        {or
          {line
            'user-id
            {or
              'min 'max
            }
            '= usernameOrUID
          }
          {line
            'group-id
            {or
              'min 'max
            }
            '= groupnameOrUID
          }
          {loop
            {line
              'file '= asciiFtpFile
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
