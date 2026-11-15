# CIDR
set all_graphs {
  tac_plus/CIDR
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
