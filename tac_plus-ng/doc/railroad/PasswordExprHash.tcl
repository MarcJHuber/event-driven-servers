# PasswordExprHash
set all_graphs {
  tac_plus-ng/PasswordExpr
  {line
    {or
      {line
        'clear cleartextPassword
      }
      {line
        'crypt hashedPassword
      }
      {line
        '4 ciscoIOSType4Password
      }
      {line
        '5 ciscoIOSType5Password
      }
      {line
        '7 ciscoIOSType7Password
      }
      {line
        '8 ciscoIOSType8Password
      }
      {line
        '9 ciscoIOSType9Password
      }
      {line
        'pbkdf2 ciscoAsaPbdkf2Password
      }
      {line
        'asa ciscoAsaMD5Password
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
