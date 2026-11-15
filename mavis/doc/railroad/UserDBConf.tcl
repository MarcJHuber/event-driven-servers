# UserDBConf
set all_graphs {
  mavis/UserDBConf
  {stack
    {line
      'mavis 'module '= 'userdb
    }
    {line
      '{
      {toploop
        {or
          {line 'userid '= userID }
            {line 'groupid '= groupID }
              {line 'home '= homeDirectory }
                {line 'password '= {or
                  {line 'clear cleartextPassword }
                    {line 'crypt hashedPassword }
                      {line 'mavis }
                      }
                    }
                    {line 'root '= rootDirectory }
                      {line 'cert 'subject '= certSubject }
                        {line 'set attribute '= value }
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
