# ACLDecl
set all_graphs {
  tac_plus/ACLDecl
  {line
    'acl
    {or
      {line
        '= aclName {optx
        {or
          'permit
          'deny
        }
      } '{ AclExpr '}
    }
    {line
      'script '= aclName '{ TacAction '}
    }
  }
}
}
