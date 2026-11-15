# CIDR
set all_graphs {
  mavis/CIDR
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
