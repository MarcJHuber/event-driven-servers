# AclDecl
set all_graphs {
  spawnd/AclDecl
  {line
    {or
      'permit 'deny
    }
    {optx
      'not
    }
    CIDR
  }
}
