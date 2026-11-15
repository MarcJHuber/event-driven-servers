# CIDR
set all_graphs {
  spawnd/CIDR
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
