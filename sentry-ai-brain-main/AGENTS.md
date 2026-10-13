<!-- LOVABLE:BEGIN -->
> [!IMPORTANT]
> This project is connected to [Lovable](https://lovable.dev). Avoid rewriting
> published git history — force pushing, or rebasing/amending/squashing commits
> that are already pushed — as it rewrites history on Lovable's side and the
> user will likely lose their project history.
>
> Commits you push to the connected branch sync back to Lovable and show up in
> the editor, so keep the branch in a working state.
<!-- LOVABLE:END -->

## SENTINEL-X architecture
- Keep domain contracts in `src/types`, demo records in `src/data`, and backend adapters in `src/services/api`; this keeps simulated output explicit and allows a future FastAPI swap without rewriting UI.
- Keep route modules thin and compose screens from `src/pages` and `src/components/sentinel`; this prevents route files from becoming monolithic.
- Keep workflow state in the SENTINEL-X context provider; this preserves one coherent demo journey across independently shareable routes.
