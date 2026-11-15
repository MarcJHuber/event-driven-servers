# TLSExpr
set all_graphs {
  ftpd/TLSExpr
  {line
    {or
      'tls 'ssl
    }
    {or
      {line
        'cert '= certFile
      }
      {line
        'key '= keyFile
      }
      {line
        'passphrase '= passPhrase
      }
      {line
        'ca-file '= caFile
      }
      {line
        'ca-path '= caPath
      }
      {line
        'auth '=
        {or
          'yes 'no
        }
      }
      {line
        'required '=
        {or
          'yes 'no
        }
      }
      {line
        'depth '= digit
      }
      {line
        'ciphers '= ciphers
      }
      {line
        'old-draft '=
        {or
          'yes 'no
        }
      }
    }
  }
}
