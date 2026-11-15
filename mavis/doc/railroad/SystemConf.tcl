# SystemConf
set all_graphs {
  mavis/SystemConf
  {stack
    {line
      'mavis 'module '= 'system
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
            'passwd '= passwdFile
          }
          {line
            'ftpusers '= ftpUsersFile
          }
          {line
            'shells '= shellsFile
          }
          {line
            'sslusers '= sslUsersFile
          }
          {line
            'check '=
            {or
              'ftpusers 'shells 'sslusers
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
