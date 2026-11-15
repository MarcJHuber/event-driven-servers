# LogExpr
set all_graphs {
  ftpd/LogExpr
  {line
    'log
    {optx
      Acl
    }
    '=
    {toploop
      {or
        'none 'command 'transfer 'event 'ident
      }
    }
  }
}
