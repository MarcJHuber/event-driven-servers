# PasswordExprHash
set all_graphs {
  tac_plus/PasswordExprHash
  {or
    PasswdExpr 'login
    {line
      'crypt hashedPassword
    }
  }
}
