# ShellCommandDecl
set all_graphs {
  tac_plus-ng/ShellCommandDecl
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
