# EnableExpr
set all_graphs {
  tac_plus/EnableExpr
  {line
    'enable
    {optx
      level
    }
    '=
    {or
      {line
        'clear cleartextPassword
      }
      {line
        '7 obscuredPassword
      }
      {line
        'crypt hashedPassword
      }
      {line
        'login
      }
      {line
        'permit
      }
      {line
        'deny
      }
    }
  }
}
