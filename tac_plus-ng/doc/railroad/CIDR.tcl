# CIDR
set all_graphs {
  tac_plus-ng/CIDR
  {line
    internetAddress
    {optx
      '/
      {or
        'maskLen 'internetMask
      }
    }
  }
}
