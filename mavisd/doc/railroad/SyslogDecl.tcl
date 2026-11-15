# SyslogDecl
set all_graphs {
  spawnd/SyslogDecl
  {line
    'syslog
    {or
      'facility 'level 'ident
    }
    '= string
  }
}
