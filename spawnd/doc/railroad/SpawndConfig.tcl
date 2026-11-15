# SpawndDecl
set all_graphs {
  spawnd/SpawndConfig
  {stack
    {line 'id '= 'spawnd }
      {line '{
        {toploop
          {or
            {line Debug }
              {line SyslogDecl }
                {line AclDecl }
                  {line MiscDecl }
                    {line ListenDecl }
                      {line ChildDecl }
                      }
                    }
                    '}
                  }
                }
              }
