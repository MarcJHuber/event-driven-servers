# SyslogDecl
set all_graphs {
  spawnd/SyslogDecl
  {line
    'syslog
    {or
      'facility 'severity 'ident
    }
    '= string
  }
}
