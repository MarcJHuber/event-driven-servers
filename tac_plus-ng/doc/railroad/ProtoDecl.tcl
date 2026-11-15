# ProtoDecl
set all_graphs {
  tac_plus-ng/ProtoDecl
  {line
    'protocol '= protocolName
    {opt
      '{
      {toploop
        {or
          AttrDefault Acl AVPair UserMessage
        }
        {
        }
      }
      '}
    }
  }
}
