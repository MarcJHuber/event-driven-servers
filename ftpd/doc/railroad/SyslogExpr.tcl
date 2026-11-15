# SyslogExpr
set all_graphs {
  ftpd/SyslogExpr
  {line
    'syslog
    {or
      'facility 'severity 'ident
    }
    '= string
  }
}
