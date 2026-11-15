# GlobalDecl
set all_graphs {
  tac_plus-ng/GlobalDecl
  {or
    {line
      'umask '= umask
    }
    {line
      'syslog
      {or
        'facility 'level
      }
      '= string
    }
    {line
      'working 'directory '= directory
    }
    {line
      'coredump 'directory '= directory
    }
    {line
      'retire
      {or
        {line
          'limit '= count
        }
        {line
          'seconds '= seconds
        }
      }
    }
    {line
      'last-recently-used limit = n
    }
    {line
      'time 'zone '= timeZone
    }
  }
}
