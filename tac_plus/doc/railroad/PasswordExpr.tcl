# PasswordExpr
set all_graphs {
  tac_plus/PasswordExpr
  {or
    {line
      'clear cleartextPassword
    }
    {line
      '7 obscuredPassword
    }
    'permit 'deny
  }
}
