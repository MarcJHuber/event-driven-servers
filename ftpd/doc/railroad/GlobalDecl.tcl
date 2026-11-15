# GlobalDecl
set all_graphs {
  ftpd/GlobalDecl
  {or
    {line
      'mimetypes '= mimeTypesFile
    }
    {line
      'use-sendfile '=
      {or
        'yes 'no
      }
    }
    {line
      'use-mmap '=
      {or
        'yes 'no
      }
    }
    {line
      'nlst '= 'files-only
    }
    {line
      'hide-version '=
      {or
        'yes 'no
      }
    }
    {line
      'buffer
      {or
        'size 'mmap-size
      }
      '= bytes
    }
  }
}
