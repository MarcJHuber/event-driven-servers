# PasswordExpr
set all_graphs {
  tac_plus-ng/PasswordExpr
  {line
    {or
      {line
        'clear cleartextPassword
      }
      {line
        '7 ciscoIOSType7Password
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
      {line
        'error
      }
    }
  }
}
