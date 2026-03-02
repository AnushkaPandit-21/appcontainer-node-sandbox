{
  "targets": [
    {
      "target_name": "appcontainer",
      "sources": [
        "native/appcontainer.cc",
        "native/wfp_rules.cc"
      ],
      "include_dirs": [
        "<!(node -p \"require('path').resolve(require('node-addon-api').include_dir)\")",
        "native"
      ],
      "defines": [
        "NAPI_DISABLE_CPP_EXCEPTIONS"
      ],
      "conditions": [
        [
          "OS=='win'",
          {
            "libraries": [
              "userenv.lib",
              "Fwpuclnt.lib",
              "Advapi32.lib"
            ],
            "msvs_settings": {
              "VCCLCompilerTool": {
                "ExceptionHandling": 1,
                "AdditionalOptions": ["/std:c++17"]
              }
            },
            "defines": [
              "WIN32_LEAN_AND_MEAN",
              "UNICODE",
              "_UNICODE",
              "NTDDI_VERSION=NTDDI_WIN8",
              "_WIN32_WINNT=0x0602"
            ]
          }
        ],
        [
          "OS!='win'",
          {
            "sources": [],
            "message": "appcontainer addon is only supported on Windows"
          }
        ]
      ]
    }
  ]
}
