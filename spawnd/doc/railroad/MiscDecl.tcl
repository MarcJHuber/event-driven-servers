# MiscDecl
set all_graphs {
  spawnd/MiscDecl
  {or
    {line
      'overload '=
      {or
        'queue 'close 'reset
      }
    }
    {line
      'bind 'retry 'delay '= seconds
    }
    {line
      'single 'process '=
      {or
        'yes 'no
      }
    }
    {line
      'background '=
      {or
        'yes 'no
      }
    }
    {line
      'reuse-port '=
      {or
        'yes 'no
      }
    }
    {line
      'tcp 'keepalive
      {or
        'idle 'interval 'count
      } '= number
    }
    {line
      'tcp 'bufsize  '= number
    }
    {line
      'pidfile '= pathToPIDFile
    }
  }
}
