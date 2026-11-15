# LogFormatExpr
set all_graphs {
  ftpd/LogFormatExpr
  {line
    'logformat
    {or
      {line
        {or
          'command 'event 'transfer
        }
        '= logFormat
      }
      {line
        'delimiter '= character
      }
      {line
        'substitute '= character
      }
    }
  }
}
