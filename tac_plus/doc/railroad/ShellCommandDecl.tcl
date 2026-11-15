# ShellCommandDecl
set all_graphs {
  tac_plus/ShellCommandDecl
  {line
    'cmd '= command '{
    {toploop
      {or
        {line
          {or
            'permit 'deny
          }
          commandArgRegex
        }
        {line
          UserMsg
        }
        {
        }
      }
    }
    '}
  }
}
