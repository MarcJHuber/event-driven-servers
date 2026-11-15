# AddressMismatchExpr
set all_graphs {
  ftpd/AddressMismatchExpr
  {line
    'address-mismatch
    {optx
      Acl
    }
    '=
    {or
      'permit 'deny
    }
  }
}
