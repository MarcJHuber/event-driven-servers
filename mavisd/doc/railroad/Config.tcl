# Config
set all_graphs {
  mavisd/Config
  {stack
    {line 'id '= 'mavisd }
      {line '{
        {or
          {line {or 'permit 'deny } {optx 'not } CIDR }
            {line 'background '= {or 'permit 'deny } }
              {line 'pidfile '= pathToPIDFile }
                {line 'stat 'period '= seconds }
                  {line 'transmit 'password '= {or 'permit 'deny } }
                    {line 'listen '= '{
                      {or
                        {toploop
                          {or
                            {line 'path '= unixPath }
                              {line 'user-id '= uidNumber }
                                {line 'group-id '= gidNumber }
                                  {line 'mode '= octalFileMode }
                                  }
                                }
                                {toploop
                                  {or
                                    {line 'address '= ipAddress }
                                      {line 'port '= udpPort }
                                      }
                                    }
                                    {line
                                      'blowfish
                                      {or
                                        {line 'key '= key }
                                          {line 'keyfile '= keyFile }
                                          }
                                        }
                                      }
                                      '}
                                    }
                                    {line SyslogDecl }
                                    }
                                    '}
                                  }
                                }
                              }
