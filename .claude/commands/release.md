# Release Command

以下の手順で自動リリースを実行してください：

1. 現在のgit statusを確認
2. 変更があれば、日本語でコミットメッセージを作成（変更内容に基づく）
3. コミットを実行
4. 最新のタグを取得してパッチバージョンをインクリメント
5. 新しいタグを作成
6. コミットとタグをリモートにプッシュ
7. GitHub CLIを使用してリリースを作成（`gh release create`コマンド）

## コミットメッセージのフォーマット

```
<type>: <変更内容の日本語説明>

<詳細な説明（必要に応じて）>

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>
```

type は以下から選択：
- feat: 新機能
- fix: バグ修正
- docs: ドキュメントのみの変更
- style: コードの意味に影響しない変更
- refactor: リファクタリング
- test: テストの追加・修正
- chore: ビルドプロセスやツールの変更

## リリースノート

GitHubリリースのノートには、コミットメッセージの主要部分を含めてください。
