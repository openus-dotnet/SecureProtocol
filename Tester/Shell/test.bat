for %%a in (0 5 10 15 20 25) do (
    for %%b in (1 10 100 1000) do (
        for %%r in (0 0 0 0 0) do (
            .\Tester.exe n %%a %%b
        )
    )
)